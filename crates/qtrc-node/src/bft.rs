//! Running as one of several validators (BFT).
//!
//! Each validator listens on its `--p2p` address for consensus messages
//! (votes, and proposals with their block), transactions relayed by other
//! validators, and block requests from validators catching up. Messages go
//! out over plain HTTP: everything that matters in them is signed with
//! HYDRA-X and checked on arrival, so the transport does not need to be
//! trusted, only to deliver.
//!
//! The consensus itself runs on one thread (`Driver`): Malachite's state
//! machine through `qtrc_bft::runner`, fed by the network, by timers, and
//! by a tick that starts the next height only when there are transactions
//! to put in it (no empty blocks, as before).

use crate::follow::{self, BlockSource};
use crate::store::{self, BlockStore};
use anyhow::{bail, Context, Result};
use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, Path, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use qtrc_bft::runner::{Action, Runner, SignGuard};
use qtrc_bft::types::{LinearTimeouts, Timeout};
use qtrc_bft::wire::{self, WireMsg};
use qtrc_bft::{BlockId, Height};
use qtrc_common::block::Block;
use qtrc_common::tx::Transaction;
use qtrc_consensus::ConsensusEngine;
use qtrc_crypto::{Address, HydraXKeypair};
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info, warn};

/// `--bft-config` file: who the validators are, where to reach them, and
/// from which height blocks are decided by their votes.
#[derive(Clone, Debug, Deserialize)]
pub struct BftConfig {
    pub bft_from_height: u64,
    pub validators: Vec<PeerConfig>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct PeerConfig {
    /// 64-hex HYDRA-X address
    pub address: String,
    /// Its `--p2p` listener, e.g. http://203.0.113.7:9545
    pub p2p: String,
}

#[derive(Clone)]
pub struct Peer {
    pub address: Address,
    pub url:     String,
}

impl BftConfig {
    pub fn load(path: &str) -> Result<(u64, Vec<Peer>)> {
        let text = std::fs::read_to_string(path).with_context(|| format!("reading {path}"))?;
        let c: BftConfig = serde_json::from_str(&text).with_context(|| format!("parsing {path}"))?;
        if c.bft_from_height == 0 {
            bail!("bft_from_height must be at least 1");
        }
        let mut seen = HashSet::new();
        let mut peers = Vec::new();
        for v in c.validators {
            let address = Address::from_hex(&v.address).map_err(|e| anyhow::anyhow!("validator {}: {e}", v.address))?;
            if !seen.insert(address.clone()) {
                bail!("validator {} listed twice", v.address);
            }
            peers.push(Peer { address, url: v.p2p.trim_end_matches('/').to_string() });
        }
        if peers.len() < 4 {
            warn!("{} validators: with fewer than 4, one failure stops the chain", peers.len());
        }
        Ok((c.bft_from_height, peers))
    }
}

/// Timeouts sized for HYDRA-X: a proposal can carry 500 transactions to
/// verify, and SLH-DSA signing takes a noticeable fraction of a second.
fn timeouts() -> LinearTimeouts {
    LinearTimeouts {
        propose: Duration::from_secs(10),
        propose_delta: Duration::from_secs(2),
        prevote: Duration::from_secs(3),
        prevote_delta: Duration::from_secs(1),
        precommit: Duration::from_secs(3),
        precommit_delta: Duration::from_secs(1),
        rebroadcast: Duration::from_secs(15),
        ..Default::default()
    }
}

enum Event {
    Msg(WireMsg),
    Timeout { height: u64, timeout: Timeout },
}

/// Handle for the rest of the node: where network input goes.
#[derive(Clone)]
pub struct Inbox(Sender<Event>);

impl Inbox {
    fn msg(&self, m: WireMsg) {
        let _ = self.0.send(Event::Msg(m));
    }
}

/// Sends to the other validators, each send on its own thread so a slow or
/// dead peer never holds up the consensus.
#[derive(Clone)]
pub struct Outbox {
    peers:  Arc<Vec<Peer>>,
    me:     Address,
    client: reqwest::blocking::Client,
}

impl Outbox {
    pub fn new(peers: Vec<Peer>, me: Address) -> Result<Self> {
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(20))
            .user_agent(concat!("qtrc-node/", env!("CARGO_PKG_VERSION"), " bft"))
            .build()?;
        Ok(Outbox { peers: Arc::new(peers), me, client })
    }

    fn others(&self) -> impl Iterator<Item = &Peer> {
        self.peers.iter().filter(move |p| p.address != self.me)
    }

    fn broadcast(&self, path: &'static str, body: Vec<u8>, content_type: &'static str) {
        let body = Arc::new(body);
        for p in self.others() {
            let (client, url, body) = (self.client.clone(), format!("{}{path}", p.url), body.clone());
            std::thread::spawn(move || {
                let r = client.post(&url).header("content-type", content_type).body(body.to_vec()).send();
                match r {
                    Ok(r) if r.status().is_success() => {}
                    Ok(r) => debug!(%url, status = %r.status(), "peer refused"),
                    Err(e) => debug!(%url, "peer unreachable: {e}"),
                }
            });
        }
    }

    /// Pass a transaction a client sent us to the other validators, so
    /// whichever of them proposes next has it.
    pub fn relay_tx(&self, tx: &Transaction) {
        if let Ok(body) = serde_json::to_vec(tx) {
            self.broadcast("/p2p/v1/tx", body, "application/json");
        }
    }

    /// Other validators' p2p listeners as block sources, for catching up.
    fn sources(&self) -> Vec<Box<dyn BlockSource>> {
        self.others()
            .filter_map(|p| follow::HttpPeer::new(&format!("{}/p2p/v1", p.url)).ok())
            .map(|p| Box::new(p) as Box<dyn BlockSource>)
            .collect()
    }
}

/// The consensus loop. Owns the runner; everything reaches it as events.
pub struct Driver {
    engine:   Arc<ConsensusEngine>,
    key:      Arc<HydraXKeypair>,
    out:      Outbox,
    tx:       Sender<Event>,
    rx:       Receiver<Event>,
    runner:   Option<Runner>,
    /// Height the runner is working on, if started.
    running:  Option<u64>,
    /// Blocks seen in proposals (ours and others'), by header hash.
    blocks:   HashMap<BlockId, Block>,
    /// Messages for a height we have not started yet.
    later:    Vec<WireMsg>,
    timers:   HashSet<Timeout>,
    /// Last time we asked the others how far they are.
    last_sync: std::time::Instant,
}

/// How often an idle validator checks whether it fell behind (after a
/// restart, or a network cut while blocks were being decided).
const SYNC_EVERY: Duration = Duration::from_secs(10);

const MAX_LATER: usize = 2_000;

impl Driver {
    pub fn new(engine: Arc<ConsensusEngine>, key: HydraXKeypair, out: Outbox, guard: SignGuard) -> Result<(Self, Inbox)> {
        let key = Arc::new(key);
        let (tx, rx) = mpsc::channel();
        let next = engine.state.read().height + 1;
        let vs = engine.bft_validator_set().map_err(|e| anyhow::anyhow!("{e}"))?;
        let runner = Runner::new(key.clone(), vs, Height(next), guard, timeouts());
        let inbox = Inbox(tx.clone());
        Ok((
            Driver { engine, key, out, tx, rx, runner: Some(runner), running: None, blocks: HashMap::new(), later: Vec::new(), timers: HashSet::new(), last_sync: std::time::Instant::now() - SYNC_EVERY },
            inbox,
        ))
    }

    fn next_height(&self) -> u64 {
        self.engine.state.read().height + 1
    }

    pub fn run(mut self) {
        info!(address = %self.key.address(), "BFT validator running");
        loop {
            match self.rx.recv_timeout(Duration::from_secs(1)) {
                Ok(Event::Msg(m)) => self.on_msg(m),
                Ok(Event::Timeout { height, timeout }) => {
                    if self.running == Some(height) && self.timers.remove(&timeout) {
                        let a = self.runner_mut().timeout(timeout);
                        self.act(a);
                    }
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => return,
            }
            self.tick();
        }
    }

    fn runner_mut(&mut self) -> &mut Runner {
        self.runner.as_mut().expect("runner present")
    }

    /// Start the next height when there is work: our own pending
    /// transactions, or another validator already voting on it.
    fn tick(&mut self) {
        if self.running.is_none() && self.last_sync.elapsed() >= SYNC_EVERY {
            self.catch_up();
        }
        let next = self.next_height();
        if self.running.is_some_and(|h| h < next) {
            // Committed past what the runner was doing (caught up): start
            // over at the new height with the same sign guard.
            self.reset_runner(next);
        }
        if self.running.is_none() && !self.engine.mempool.read().is_empty() {
            self.start(next);
        }
    }

    fn reset_runner(&mut self, next: u64) {
        let guard = self.runner.take().expect("runner present").into_guard();
        let vs = self.engine.bft_validator_set().expect("validator set");
        self.runner = Some(Runner::new(self.key.clone(), vs, Height(next), guard, timeouts()));
        self.running = None;
        self.timers.clear();
        self.blocks.retain(|_, b| b.header.height >= next);
    }

    fn start(&mut self, h: u64) {
        let vs = match self.engine.bft_validator_set() {
            Ok(vs) => vs,
            Err(e) => return warn!("cannot start height {h}: {e}"),
        };
        debug!(height = h, "starting consensus height");
        self.running = Some(h);
        self.timers.clear();
        let a = self.runner_mut().start_height(Height(h), vs);
        self.act(a);
        // Messages that arrived early.
        let (now, keep): (Vec<_>, Vec<_>) = std::mem::take(&mut self.later).into_iter().partition(|m| m.height() == h);
        self.later = keep.into_iter().filter(|m| m.height() > h).collect();
        for m in now {
            self.feed(m);
        }
    }

    fn on_msg(&mut self, m: WireMsg) {
        let next = self.next_height();
        let h = m.height();
        // Only validators' messages, and only for the next few heights.
        let sender = Address(m.sender().0);
        if !self.engine.state.read().validators.iter().any(|v| v.address == sender) {
            return;
        }
        if h < next {
            return;
        }
        if h > next {
            if self.later.len() < MAX_LATER {
                self.later.push(m);
            }
            // Others are ahead: fetch the blocks we are missing.
            self.catch_up();
            return;
        }
        if self.running != Some(h) {
            self.start(h);
        }
        self.feed(m);
    }

    fn feed(&mut self, m: WireMsg) {
        let actions = match m {
            WireMsg::Vote(v) => match v.into_signed() {
                Ok(v) => self.runner_mut().vote(v),
                Err(e) => return debug!("bad vote: {e}"),
            },
            WireMsg::Proposal(p) => {
                let (signed, bytes) = match p.into_signed() {
                    Ok(x) => x,
                    Err(e) => return debug!("bad proposal: {e}"),
                };
                let valid = match store::decode_block(&bytes) {
                    Ok(block) => {
                        let ok = BlockId(block.hash().0) == signed.message.value.0
                            && block.header.height == signed.message.height.0
                            && match self.engine.check_proposal(&block) {
                                Ok(()) => true,
                                Err(e) => {
                                    warn!(height = block.header.height, "proposed block is invalid: {e}");
                                    false
                                }
                            };
                        if ok {
                            self.blocks.insert(BlockId(block.hash().0), block);
                        }
                        ok
                    }
                    Err(e) => {
                        warn!("proposal with an undecodable block: {e}");
                        false
                    }
                };
                self.runner_mut().proposal(signed, valid)
            }
        };
        self.act(actions);
    }

    fn act(&mut self, actions: Vec<Action>) {
        for a in actions {
            match a {
                Action::Publish(m) => self.publish(m),
                Action::BuildBlock { height, round } => match self.engine.propose_block() {
                    Ok(block) => {
                        let id = BlockId(block.hash().0);
                        info!(height = height.0, round = round.as_i64(), txs = block.transactions.len(), "proposing block");
                        self.blocks.insert(id, block);
                        let more = self.runner_mut().propose(height, round, id);
                        self.act(more);
                    }
                    // Nothing to propose: the round times out and the next
                    // validator, who may have the transactions, proposes.
                    Err(e) => info!(height = height.0, "not proposing: {e}"),
                },
                Action::ScheduleTimeout(t, d) => {
                    let Some(height) = self.running else { continue };
                    self.timers.insert(t);
                    let tx = self.tx.clone();
                    std::thread::spawn(move || {
                        std::thread::sleep(d);
                        let _ = tx.send(Event::Timeout { height, timeout: t });
                    });
                }
                Action::CancelTimeout(t) => {
                    self.timers.remove(&t);
                }
                Action::CancelAllTimeouts => self.timers.clear(),
                Action::Decided(cert) => {
                    let Some(mut block) = self.blocks.get(&cert.value_id).cloned() else {
                        warn!(height = cert.height.0, "decided a block we do not have; fetching it");
                        self.catch_up();
                        continue;
                    };
                    let Some(proof) = qtrc_bft::commit_proof(&cert) else {
                        warn!("could not build the commit proof");
                        continue;
                    };
                    block.commit = Some(proof);
                    match self.engine.commit_block(block) {
                        Ok(()) => info!(height = cert.height.0, round = cert.round.as_i64(), signers = cert.commit_signatures.len(), "block decided by the validators"),
                        Err(e) => warn!(height = cert.height.0, "decided block failed to commit: {e}"),
                    }
                }
                Action::Finalized(h) => {
                    if self.running == Some(h.0) {
                        self.running = None;
                        self.timers.clear();
                        self.blocks.retain(|_, b| b.header.height > h.0);
                    }
                }
            }
        }
    }

    fn publish(&self, m: qtrc_bft::consensus::SignedConsensusMsg<qtrc_bft::Ctx>) {
        use qtrc_bft::consensus::SignedConsensusMsg as S;
        let msg = match &m {
            S::Vote(v) => WireMsg::from(v),
            S::Proposal(p) => {
                let Some(block) = self.blocks.get(&p.message.value.0) else {
                    return warn!("proposal for a block we do not have");
                };
                match store::encode_block(block) {
                    Ok(bytes) => wire::proposal_msg(p, bytes),
                    Err(e) => return warn!("cannot encode block: {e}"),
                }
            }
        };
        self.out.broadcast("/p2p/v1/consensus", msg.encode(), "application/octet-stream");
    }

    /// Fetch committed blocks we are missing from the other validators.
    /// Each comes with its commit proof and is fully checked.
    fn catch_up(&mut self) {
        self.last_sync = std::time::Instant::now();
        let synced = follow::sync_once(&self.engine, &self.out.sources());
        if synced.stored > 0 {
            info!(stored = synced.stored, height = synced.height, "caught up from other validators");
            self.reset_runner(synced.height + 1);
        }
    }
}

// ---------------------------------------------------------------------------
// The p2p listener
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct P2p {
    engine: Arc<ConsensusEngine>,
    store:  Arc<BlockStore>,
    inbox:  Inbox,
}

async fn post_consensus(State(st): State<P2p>, body: Bytes) -> StatusCode {
    let decoded = tokio::task::spawn_blocking(move || WireMsg::decode(&body)).await;
    match decoded {
        Ok(Ok(m)) => {
            // Cheap filter before it reaches the consensus thread; the
            // signature is checked there.
            let sender = Address(m.sender().0);
            if !st.engine.state.read().validators.iter().any(|v| v.address == sender) {
                return StatusCode::FORBIDDEN;
            }
            st.inbox.msg(m);
            StatusCode::ACCEPTED
        }
        _ => StatusCode::BAD_REQUEST,
    }
}

async fn post_tx(State(st): State<P2p>, Json(tx): Json<Transaction>) -> StatusCode {
    let engine = st.engine.clone();
    // Already known or invalid: either way nothing to do, and no relaying
    // from here (only the validator a client sent it to relays it).
    let r = tokio::task::spawn_blocking(move || engine.submit_tx(tx)).await;
    match r {
        Ok(Ok(_)) => StatusCode::ACCEPTED,
        _ => StatusCode::OK,
    }
}

#[derive(serde::Serialize)]
struct PeerStatus {
    chain_id: &'static str,
    height:   u64,
}

async fn get_status(State(st): State<P2p>) -> Json<PeerStatus> {
    Json(PeerStatus { chain_id: qtrc_common::tx::CHAIN_ID, height: st.engine.state.read().height })
}

async fn get_block(State(st): State<P2p>, Path(h): Path<u64>) -> Result<Json<Block>, StatusCode> {
    let store = st.store.clone();
    match tokio::task::spawn_blocking(move || store.get_block(h)).await {
        Ok(Ok(Some(b))) => Ok(Json(b)),
        Ok(Ok(None)) => Err(StatusCode::NOT_FOUND),
        _ => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

pub async fn serve(engine: Arc<ConsensusEngine>, store: Arc<BlockStore>, inbox: Inbox, addr: std::net::SocketAddr) -> Result<()> {
    let app = Router::new()
        .route("/p2p/v1/consensus", post(post_consensus))
        .route("/p2p/v1/tx", post(post_tx).layer(DefaultBodyLimit::max(256 * 1024)))
        .route("/p2p/v1/status", get(get_status))
        .route("/p2p/v1/block/:height", get(get_block))
        .layer(DefaultBodyLimit::max(wire::MAX_MESSAGE))
        .layer(tower::limit::ConcurrencyLimitLayer::new(16))
        .layer(tower_http::timeout::TimeoutLayer::new(Duration::from_secs(60)))
        .with_state(P2p { engine, store, inbox });
    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!("BFT p2p listening on http://{addr}/p2p/v1");
    axum::serve(listener, app).await?;
    Ok(())
}
