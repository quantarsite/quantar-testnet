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
use parking_lot::RwLock;
use qtrc_common::{
    block::{Block, BlockHeader, ValidatorSig},
    state::ChainState,
    tx::{Transaction, TxHash},
};
use qtrc_crypto::{Address, HydraXKeypair};
use std::sync::Arc;
use thiserror::Error;
use tracing::{debug, info, warn};

/// Block time in seconds.
pub const BLOCK_TIME_SECS: u64 = 5;

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
            IngestionPipeline::new(pool, sig_cache, Arc::new(PqCryptoVerifier), 0)
                .expect("ingestion pipeline init failed"),
        );

        ConsensusEngine {
            state:   Arc::new(RwLock::new(state)),
            mempool: Arc::new(RwLock::new(Vec::new())),
            keypair: Arc::new(keypair),
            address,
            pipeline,
        }
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
        let item = adapter::to_ingest_item(&tx)?;

        match self.pipeline.ingest_one(item) {
            IngestResult::Accepted { hash } => {
                self.mempool.write().push(tx);
                Ok(adapter::hx_hash_to_qtrc(hash))
            }
            IngestResult::Duplicate { hash } => Ok(adapter::hx_hash_to_qtrc(hash)),
            IngestResult::Rejected { reason } => {
                Err(ConsensusError::InvalidTx(reason.to_string()))
            }
        }
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

        // Compute len first to avoid simultaneous mutable + immutable borrow
        let txs: Vec<Transaction> = {
            let mut pool = self.mempool.write();
            let n = pool.len().min(500);
            pool.drain(..n).collect()
        };

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

    /// Commit a finalized block to the chain state.
    pub fn commit_block(&self, block: Block) -> Result<(), ConsensusError> {
        {
            let state    = self.state.read();
            let expected = state.height + 1;
            if block.header.height != expected {
                return Err(ConsensusError::WrongHeight {
                    expected,
                    got: block.header.height,
                });
            }
        }

        if !block.verify_transactions() {
            return Err(ConsensusError::InvalidTx(
                "one or more transactions failed HYDRA-X verification".into(),
            ));
        }

        self.verify_proposer_sig(&block)?;

        let mut state = self.state.write();
        state
            .apply_block(&block)
            .map_err(|e| ConsensusError::InvalidTx(e.to_string()))?;

        info!(
            height = block.header.height,
            hash   = %block.hash(),
            txs    = block.transactions.len(),
            "✅ block committed"
        );

        Ok(())
    }

    fn verify_proposer_sig(&self, block: &Block) -> Result<(), ConsensusError> {
        let header_bytes = block.header.signing_bytes();
        for vs in &block.validator_sigs {
            if vs.validator == block.header.proposer {
                vs.signature
                    .verify(&header_bytes)
                    .map_err(|e| ConsensusError::InvalidSig(e.to_string()))?;
                return Ok(());
            }
        }
        if block.validator_sigs.is_empty() {
            warn!("block has no validator signatures — single-node mode");
            return Ok(());
        }
        Err(ConsensusError::InvalidSig(
            "proposer signature not found".into(),
        ))
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

        match engine.propose_block() {
            Ok(block) => {
                if let Err(e) = engine.commit_block(block) {
                    warn!("commit failed: {e}");
                }
            }
            Err(ConsensusError::NotProposer { .. }) => {
                debug!("not proposer this slot — waiting for block from peers");
            }
            Err(e) => {
                warn!("propose error: {e}");
            }
        }
    }
}
