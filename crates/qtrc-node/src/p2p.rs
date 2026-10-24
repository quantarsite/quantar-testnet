//! Node-to-node block announcements.
//!
//! A validator tells its peers right after it commits a block, so they do
//! not have to poll for it. An announcement is the block header plus the
//! proposer's HYDRA-X signature over it (ML-DSA-87 AND SLH-DSA-SHA2-256s),
//! exactly as the block carries them. Nothing new is signed, and nothing in
//! an announcement is trusted: the receiver checks that it comes from the
//! expected validator, verifies the signature, and only then fetches the
//! block, which goes through the full commit checks like any other.
//!
//! The listener is meant to face the internet on followers, without a
//! reverse proxy in front, so it is narrow: one route, a small body limit,
//! a few requests at a time, a timeout, and the cheap checks (size, height,
//! proposer) before the expensive one (signature).

use anyhow::Result;
use axum::{
    extract::{DefaultBodyLimit, State},
    http::StatusCode,
    routing::post,
    Json, Router,
};
use qtrc_common::block::{BlockHeader, ValidatorSig};
use qtrc_consensus::ConsensusEngine;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;
use tokio::sync::Semaphore;
use tracing::{debug, info, warn};

/// Path peers post announcements to.
pub const ANNOUNCE_PATH: &str = "/p2p/v1/announce";

/// A header with one HYDRA-X signature is about 130 KB as JSON (the
/// signature and keys are about 37 KB, written out as numbers).
const MAX_BODY: usize = 256 * 1024;
/// Signature checks at once; the rest get 429 and the next announcement.
const MAX_CONCURRENT: usize = 2;
/// Ignore announcements too far ahead of us: a real gap that large is
/// caught up by polling anyway, and it bounds what a replayed old header
/// or a confused peer can make us do.
const MAX_AHEAD: u64 = 10_000;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Announce {
    pub header: BlockHeader,
    pub sigs:   Vec<ValidatorSig>,
}

/// Wakes the follower loop early when a valid announcement arrives.
#[derive(Default)]
pub struct Wake {
    target: Mutex<u64>,
    cv:     Condvar,
}

impl Wake {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Record that a peer has a block at `height`.
    pub fn notify(&self, height: u64) {
        let mut t = self.target.lock().unwrap();
        if height > *t {
            *t = height;
            self.cv.notify_all();
        }
    }

    /// Wait until a peer has announced a block above `height`, or `timeout`.
    pub fn wait_above(&self, height: u64, timeout: Duration) {
        let t = self.target.lock().unwrap();
        let _ = self.cv.wait_timeout_while(t, timeout, |t| *t <= height);
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Valid, and newer than our tip: go fetch it.
    Fetch(u64),
    /// Valid or not, nothing to do (we have it, or it is out of range).
    Ignore,
}

/// Check an announcement. Cheap checks first, the signature last.
pub fn check(engine: &ConsensusEngine, a: &Announce) -> Result<Verdict, String> {
    let local = engine.state.read().height;
    let h = a.header.height;
    if h <= local || h > local.saturating_add(MAX_AHEAD) {
        return Ok(Verdict::Ignore);
    }
    if a.sigs.len() > 8 {
        return Err("too many signatures".into());
    }
    if engine.proposer_at(h).as_ref() != Some(&a.header.proposer) {
        return Err("not from the expected validator".into());
    }
    engine.verify_header(&a.header, &a.sigs).map_err(|e| e.to_string())?;
    Ok(Verdict::Fetch(h))
}

#[derive(Clone)]
struct P2pState {
    engine: Arc<ConsensusEngine>,
    wake:   Arc<Wake>,
    slots:  Arc<Semaphore>,
}

async fn post_announce(
    State(st): State<P2pState>,
    Json(a): Json<Announce>,
) -> (StatusCode, &'static str) {
    let Ok(_slot) = st.slots.clone().try_acquire_owned() else {
        return (StatusCode::TOO_MANY_REQUESTS, "busy");
    };
    let engine = st.engine.clone();
    let checked = tokio::task::spawn_blocking(move || check(&engine, &a)).await;
    match checked {
        Ok(Ok(Verdict::Fetch(h))) => {
            debug!(height = h, "valid block announcement");
            st.wake.notify(h);
            (StatusCode::ACCEPTED, "fetching")
        }
        Ok(Ok(Verdict::Ignore)) => (StatusCode::OK, "ignored"),
        Ok(Err(e)) => {
            warn!("rejected block announcement: {e}");
            (StatusCode::BAD_REQUEST, "rejected")
        }
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "error"),
    }
}

/// Listen for announcements on `addr` (only this route, nothing else).
pub async fn serve(engine: Arc<ConsensusEngine>, wake: Arc<Wake>, addr: std::net::SocketAddr) -> Result<()> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!("P2P announcements listening on http://{addr}{ANNOUNCE_PATH}");
    serve_on(engine, wake, listener).await
}

async fn serve_on(engine: Arc<ConsensusEngine>, wake: Arc<Wake>, listener: tokio::net::TcpListener) -> Result<()> {
    let app = Router::new()
        .route(ANNOUNCE_PATH, post(post_announce))
        .layer(DefaultBodyLimit::max(MAX_BODY))
        .layer(tower_http::timeout::TimeoutLayer::new(Duration::from_secs(15)))
        .with_state(P2pState { engine, wake, slots: Arc::new(Semaphore::new(MAX_CONCURRENT)) });
    axum::serve(listener, app).await?;
    Ok(())
}

/// After each commit, send the new block's header and signature to `peers`.
/// Best effort: a peer that is down simply polls and catches up later.
pub async fn announce_loop(engine: Arc<ConsensusEngine>, peers: Vec<String>) {
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .user_agent(concat!("qtrc-node/", env!("CARGO_PKG_VERSION"), " announce"))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            warn!("announcements disabled: {e}");
            return;
        }
    };
    let urls: Vec<String> = peers
        .iter()
        .map(|p| format!("{}{ANNOUNCE_PATH}", p.trim_end_matches('/')))
        .collect();
    info!(peers = ?urls, "announcing new blocks to peers");
    let mut commits = engine.subscribe_commits();
    while commits.changed().await.is_ok() {
        let Some((header, sigs)) = engine.tip() else { continue };
        let height = header.height;
        let body = Announce { header, sigs };
        for url in &urls {
            match client.post(url).json(&body).send().await {
                Ok(r) if r.status().is_success() => debug!(height, %url, "announced"),
                Ok(r) => warn!(height, %url, status = %r.status(), "peer did not take the announcement"),
                Err(e) => debug!(height, %url, "peer unreachable: {e}"),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use qtrc_common::genesis::{Genesis, MICRO_QTR};
    use qtrc_common::state::ValidatorInfo;
    use qtrc_common::tx::Transaction;
    use qtrc_crypto::HydraXKeypair;

    /// A leader with one committed block, and a follower at height 0 that
    /// knows the leader as the validator.
    fn setup() -> (ConsensusEngine, ConsensusEngine, Announce) {
        let faucet = HydraXKeypair::generate();
        let leader_key = HydraXKeypair::generate();
        let mut start = Genesis::testnet_with_faucet(Some(&faucet.address().as_hex())).initial_state();
        start.validators = vec![ValidatorInfo { address: leader_key.address(), stake: 1 }];
        let leader = ConsensusEngine::new(start.clone(), leader_key);
        let to = HydraXKeypair::generate().address();
        let p = Transaction::signing_payload(&faucet.address(), &to, MICRO_QTR, 0);
        let tx = Transaction { from: faucet.address(), to, amount: MICRO_QTR, nonce: 0, timestamp: 0, signature: faucet.sign(&p), data: vec![] };
        leader.submit_tx(tx).unwrap();
        let b = leader.propose_block().unwrap();
        leader.commit_block(b).unwrap();
        let (header, sigs) = leader.tip().unwrap();
        let follower = ConsensusEngine::new(start, HydraXKeypair::generate());
        (leader, follower, Announce { header, sigs })
    }

    #[test]
    fn a_real_announcement_is_accepted() {
        let (_, follower, a) = setup();
        assert_eq!(check(&follower, &a), Ok(Verdict::Fetch(1)));
    }

    #[test]
    fn a_tampered_header_is_rejected() {
        let (_, follower, mut a) = setup();
        a.header.timestamp += 1;
        assert!(check(&follower, &a).is_err());
    }

    #[test]
    fn a_header_signed_by_someone_else_is_rejected() {
        let (_, follower, mut a) = setup();
        let mallory = HydraXKeypair::generate();
        a.sigs[0].signature = mallory.sign(&a.header.signing_bytes());
        assert!(check(&follower, &a).is_err());
        // Claiming to be the proposer does not help either.
        a.header.proposer = mallory.address();
        a.sigs[0].validator = mallory.address();
        assert!(check(&follower, &a).is_err());
    }

    #[test]
    fn old_and_far_future_heights_are_ignored_without_verifying() {
        let (leader, _, mut a) = setup();
        // The leader already has block 1.
        assert_eq!(check(&leader, &a), Ok(Verdict::Ignore));
        a.header.height = MAX_AHEAD + 5;
        let (_, follower, _) = setup();
        assert_eq!(check(&follower, &a), Ok(Verdict::Ignore));
    }

    /// Over real HTTP: the leader commits, its announcer posts the header,
    /// the follower's listener verifies it and wakes the sync loop.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_commit_reaches_the_follower_over_http() {
        let faucet = HydraXKeypair::generate();
        let leader_key = HydraXKeypair::generate();
        let mut start = Genesis::testnet_with_faucet(Some(&faucet.address().as_hex())).initial_state();
        start.validators = vec![ValidatorInfo { address: leader_key.address(), stake: 1 }];
        let leader = Arc::new(ConsensusEngine::new(start.clone(), leader_key));
        let follower = Arc::new(ConsensusEngine::new(start, HydraXKeypair::generate()));

        let wake = Wake::new();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(serve_on(follower.clone(), wake.clone(), listener));
        tokio::spawn(announce_loop(leader.clone(), vec![url]));
        tokio::time::sleep(Duration::from_millis(200)).await;

        let l = leader.clone();
        tokio::task::spawn_blocking(move || {
            let to = HydraXKeypair::generate().address();
            let p = Transaction::signing_payload(&faucet.address(), &to, MICRO_QTR, 0);
            let tx = Transaction { from: faucet.address(), to, amount: MICRO_QTR, nonce: 0, timestamp: 0, signature: faucet.sign(&p), data: vec![] };
            l.submit_tx(tx).unwrap();
            let b = l.propose_block().unwrap();
            l.commit_block(b).unwrap();
        })
        .await
        .unwrap();

        let w = wake.clone();
        let target = tokio::task::spawn_blocking(move || {
            w.wait_above(0, Duration::from_secs(30));
            *w.target.lock().unwrap()
        })
        .await
        .unwrap();
        assert_eq!(target, 1, "follower was not told about block 1");
        // An announcement only wakes the follower; it stores nothing.
        assert_eq!(follower.state.read().height, 0);
    }

    #[test]
    fn wake_returns_early_on_notify_and_times_out_otherwise() {
        let w = Wake::new();
        let t = std::time::Instant::now();
        w.wait_above(0, Duration::from_millis(50));
        assert!(t.elapsed() >= Duration::from_millis(50));
        let w2 = w.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            w2.notify(3);
        });
        let t = std::time::Instant::now();
        w.wait_above(0, Duration::from_secs(5));
        assert!(t.elapsed() < Duration::from_secs(4));
        // Already above: returns at once.
        let t = std::time::Instant::now();
        w.wait_above(2, Duration::from_secs(5));
        assert!(t.elapsed() < Duration::from_secs(1));
    }
}
