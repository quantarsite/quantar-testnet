//! Follower mode: download blocks from other nodes and check every one
//! before storing it. A follower signs nothing and proposes nothing.
//!
//! Peers are not trusted. Each block goes through the same checks a commit
//! runs: height and previous hash, transaction and witness roots, every
//! transaction's HYDRA-X signature, the expected proposer's signature, the
//! Sentinel rules and the state root. A lying peer cannot make the follower
//! store a forged block; the most it can do is stall, so several peers can
//! be given and the follower takes blocks from whichever has them.

use anyhow::{bail, Context, Result};
use qtrc_common::block::Block;
use qtrc_consensus::ConsensusEngine;
use std::time::Duration;
use tracing::{info, warn};

/// Where blocks come from. HTTP in production, in-memory in tests.
pub trait BlockSource: Send + Sync {
    fn name(&self) -> String;
    fn height(&self) -> Result<u64>;
    fn block(&self, height: u64) -> Result<Block>;
}

/// Another node's public RPC, e.g. `https://testnet.quantarnetwork.com/rpc`.
pub struct HttpPeer {
    base: String,
    client: reqwest::blocking::Client,
}

impl HttpPeer {
    pub fn new(base: &str) -> Result<Self> {
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent(concat!("qtrc-node/", env!("CARGO_PKG_VERSION"), " follower"))
            .build()?;
        Ok(HttpPeer { base: base.trim_end_matches('/').to_string(), client })
    }

    fn get(&self, path: &str) -> Result<reqwest::blocking::Response> {
        let url = format!("{}{path}", self.base);
        let r = self.client.get(&url).send().with_context(|| format!("GET {url}"))?;
        if !r.status().is_success() {
            bail!("GET {url}: {}", r.status());
        }
        Ok(r)
    }
}

impl BlockSource for HttpPeer {
    fn name(&self) -> String {
        self.base.clone()
    }

    fn height(&self) -> Result<u64> {
        #[derive(serde::Deserialize)]
        struct Status {
            chain_id: String,
            height: u64,
        }
        let s: Status = self.get("/status")?.json()?;
        if s.chain_id != qtrc_common::tx::CHAIN_ID {
            bail!("peer runs chain {}, not {}", s.chain_id, qtrc_common::tx::CHAIN_ID);
        }
        Ok(s.height)
    }

    fn block(&self, height: u64) -> Result<Block> {
        Ok(self.get(&format!("/block/{height}"))?.json()?)
    }
}

/// What one sync pass did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Synced {
    pub stored: u64,
    pub height: u64,
    /// Best height any peer reported.
    pub target: u64,
}

/// Fetch, check and store every block the peers have and we do not.
/// Stops at the first height no peer can supply a valid block for.
pub fn sync_once(engine: &ConsensusEngine, peers: &[Box<dyn BlockSource>]) -> Synced {
    let local = engine.state.read().height;
    let heights: Vec<Option<u64>> = peers
        .iter()
        .map(|p| match p.height() {
            Ok(h) => Some(h),
            Err(e) => {
                warn!(peer = %p.name(), "peer unreachable: {e:#}");
                None
            }
        })
        .collect();
    let target = heights.iter().flatten().copied().max().unwrap_or(local);
    let mut stored = 0;
    'heights: for h in local + 1..=target {
        for (peer, ph) in peers.iter().zip(&heights) {
            if ph.is_none_or(|ph| ph < h) {
                continue;
            }
            let block = match peer.block(h) {
                Ok(b) => b,
                Err(e) => {
                    warn!(peer = %peer.name(), height = h, "could not fetch block: {e:#}");
                    continue;
                }
            };
            if block.header.height != h {
                warn!(peer = %peer.name(), height = h, got = block.header.height, "peer sent the wrong height");
                continue;
            }
            // Full verification, then durable storage, in one step.
            match engine.commit_block(block) {
                Ok(()) => {
                    stored += 1;
                    continue 'heights;
                }
                Err(e) => warn!(peer = %peer.name(), height = h, "rejected block from peer: {e}"),
            }
        }
        warn!(height = h, "no peer supplied a valid block; will retry");
        break;
    }
    let height = engine.state.read().height;
    if stored > 0 {
        info!(stored, height, target, "synced from peers");
    }
    Synced { stored, height, target }
}

/// Keep following the peers. Runs on its own thread (blocking HTTP).
pub fn run(engine: std::sync::Arc<ConsensusEngine>, peers: Vec<Box<dyn BlockSource>>) {
    loop {
        let s = sync_once(&engine, &peers);
        // Catching up: go straight on. At the tip: wait for the next block.
        if s.stored == 0 || s.height >= s.target {
            std::thread::sleep(Duration::from_secs(qtrc_consensus::BLOCK_TIME_SECS));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use qtrc_common::genesis::{Genesis, MICRO_QTR};
    use qtrc_common::state::ChainState;
    use qtrc_common::tx::Transaction;
    use qtrc_crypto::HydraXKeypair;
    use std::sync::Mutex;

    /// A peer serving a fixed chain, optionally tampering with one block.
    struct MemPeer {
        blocks: Vec<Block>,
        tamper: Option<u64>,
        served: Mutex<u64>,
    }

    impl BlockSource for MemPeer {
        fn name(&self) -> String {
            format!("mem(tamper={:?})", self.tamper)
        }
        fn height(&self) -> Result<u64> {
            Ok(self.blocks.len() as u64)
        }
        fn block(&self, h: u64) -> Result<Block> {
            *self.served.lock().unwrap() += 1;
            let mut b = self.blocks[(h - 1) as usize].clone();
            if self.tamper == Some(h) {
                b.transactions[0].amount += 1;
            }
            Ok(b)
        }
    }

    fn peer(blocks: &[Block], tamper: Option<u64>) -> Box<dyn BlockSource> {
        Box::new(MemPeer { blocks: blocks.to_vec(), tamper, served: Mutex::new(0) })
    }

    /// A leader that mines `n` blocks, and the state a follower starts from
    /// (same genesis, the leader as the only validator).
    fn chain(n: u64) -> (Vec<Block>, ChainState, ChainState) {
        let faucet = HydraXKeypair::generate();
        let leader_key = HydraXKeypair::generate();
        let mut start = Genesis::testnet_with_faucet(Some(&faucet.address().as_hex())).initial_state();
        start.validators = vec![qtrc_common::state::ValidatorInfo { address: leader_key.address(), stake: 1 }];
        let leader = ConsensusEngine::new(start.clone(), leader_key);
        let mut blocks = Vec::new();
        for nonce in 0..n {
            let to = HydraXKeypair::generate().address();
            let p = Transaction::signing_payload(&faucet.address(), &to, MICRO_QTR, nonce);
            let tx = Transaction {
                from: faucet.address(),
                to,
                amount: MICRO_QTR,
                nonce,
                timestamp: 0,
                signature: faucet.sign(&p),
                data: vec![],
            };
            leader.submit_tx(tx).unwrap();
            let b = leader.propose_block().unwrap();
            leader.commit_block(b.clone()).unwrap();
            blocks.push(b);
        }
        let end = leader.state.read().clone();
        (blocks, start, end)
    }

    #[test]
    fn follower_with_another_key_catches_up_to_the_same_state() {
        let (blocks, start, end) = chain(4);
        let follower = ConsensusEngine::new(start, HydraXKeypair::generate());
        let s = sync_once(&follower, &[peer(&blocks, None)]);
        assert_eq!(s, Synced { stored: 4, height: 4, target: 4 });
        assert_eq!(follower.state.read().state_root(), end.state_root());
        assert_eq!(follower.state.read().block_hash, end.block_hash);
        // At the tip: nothing to do.
        assert_eq!(sync_once(&follower, &[peer(&blocks, None)]).stored, 0);
    }

    #[test]
    fn a_lying_peer_is_skipped_and_an_honest_one_used() {
        let (blocks, start, end) = chain(3);
        let follower = ConsensusEngine::new(start, HydraXKeypair::generate());
        let s = sync_once(&follower, &[peer(&blocks, Some(2)), peer(&blocks, None)]);
        assert_eq!(s.height, 3);
        assert_eq!(follower.state.read().block_hash, end.block_hash);
    }

    #[test]
    fn only_lying_peers_stop_the_follower_before_the_forged_block() {
        let (blocks, start, _) = chain(3);
        let follower = ConsensusEngine::new(start, HydraXKeypair::generate());
        let s = sync_once(&follower, &[peer(&blocks, Some(2))]);
        assert_eq!((s.stored, s.height, s.target), (1, 1, 3));
    }

    #[test]
    fn blocks_from_an_unexpected_validator_are_refused() {
        let (blocks, mut start, _) = chain(2);
        // The follower expects someone else as the validator.
        start.validators[0].address = HydraXKeypair::generate().address();
        let follower = ConsensusEngine::new(start, HydraXKeypair::generate());
        let s = sync_once(&follower, &[peer(&blocks, None)]);
        assert_eq!(s.height, 0);
    }
}
