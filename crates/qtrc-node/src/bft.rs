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
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TrySendError};
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

/// Events waiting for the consensus thread. Network messages beyond this
/// are refused (the sender retries or the round times out); timers always
/// get in.
const INBOX_CAPACITY: usize = 4_096;

/// Handle for the rest of the node: where network input goes.
#[derive(Clone)]
pub struct Inbox(SyncSender<Event>);

impl Inbox {
    /// False if the consensus thread is too far behind to take more.
    fn msg(&self, m: WireMsg) -> bool {
        match self.0.try_send(Event::Msg(m)) {
            Ok(()) => true,
            Err(TrySendError::Full(_)) => false,
            Err(TrySendError::Disconnected(_)) => false,
        }
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
    tx:       SyncSender<Event>,
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
        let (tx, rx) = mpsc::sync_channel(INBOX_CAPACITY);
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
            if st.inbox.msg(m) {
                StatusCode::ACCEPTED
            } else {
                StatusCode::SERVICE_UNAVAILABLE
            }
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

/// Who may talk to the p2p listener, and how fast.
///
/// Only the validators' own addresses (resolved from the `p2p` URLs in the
/// BFT config, again every few minutes in case a host's address changes)
/// get past the door; anyone else is refused before a byte of the body is
/// read. Each allowed address then has a token bucket, so even a
/// misbehaving or compromised validator cannot flood the others.
pub struct Gate {
    allowed: parking_lot::RwLock<HashSet<std::net::IpAddr>>,
    buckets: parking_lot::Mutex<HashMap<std::net::IpAddr, Bucket>>,
    rate:    f64,
    burst:   f64,
}

struct Bucket {
    tokens: f64,
    last:   std::time::Instant,
}

/// Requests per second per validator, and the burst allowed above it. A
/// round is a handful of messages per validator; rebroadcasts and catch-up
/// stay far below this.
const RATE: f64 = 50.0;
const BURST: f64 = 200.0;

impl Gate {
    pub fn new(allowed: HashSet<std::net::IpAddr>, rate: f64, burst: f64) -> Self {
        Gate { allowed: parking_lot::RwLock::new(allowed), buckets: Default::default(), rate, burst }
    }

    pub fn set_allowed(&self, allowed: HashSet<std::net::IpAddr>) {
        *self.allowed.write() = allowed;
    }

    /// Ok, or the status to refuse with.
    pub fn check(&self, ip: std::net::IpAddr, now: std::time::Instant) -> Result<(), StatusCode> {
        if !self.allowed.read().contains(&ip) {
            return Err(StatusCode::FORBIDDEN);
        }
        let mut buckets = self.buckets.lock();
        let b = buckets.entry(ip).or_insert(Bucket { tokens: self.burst, last: now });
        let elapsed = now.saturating_duration_since(b.last).as_secs_f64();
        b.tokens = (b.tokens + elapsed * self.rate).min(self.burst);
        b.last = now;
        if b.tokens < 1.0 {
            return Err(StatusCode::TOO_MANY_REQUESTS);
        }
        b.tokens -= 1.0;
        Ok(())
    }
}

/// IP addresses the validators' `p2p` URLs resolve to.
pub fn resolve_peers(peers: &[Peer]) -> HashSet<std::net::IpAddr> {
    use std::net::ToSocketAddrs;
    let mut ips = HashSet::new();
    for p in peers {
        let Ok(url) = reqwest::Url::parse(&p.url) else {
            warn!(url = %p.url, "unparsable p2p URL");
            continue;
        };
        let (Some(host), Some(port)) = (url.host_str(), url.port_or_known_default()) else { continue };
        match (host, port).to_socket_addrs() {
            Ok(addrs) => ips.extend(addrs.map(|a| a.ip())),
            Err(e) => warn!(%host, "cannot resolve validator host: {e}"),
        }
    }
    ips
}

async fn gatekeeper(
    State(gate): State<Arc<Gate>>,
    axum::extract::ConnectInfo(peer): axum::extract::ConnectInfo<std::net::SocketAddr>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    match gate.check(peer.ip(), std::time::Instant::now()) {
        Ok(()) => next.run(req).await,
        Err(status) => {
            debug!(ip = %peer.ip(), %status, "p2p request refused");
            status.into_response()
        }
    }
}

fn router(engine: Arc<ConsensusEngine>, store: Arc<BlockStore>, inbox: Inbox, gate: Arc<Gate>) -> Router {
    Router::new()
        .route("/p2p/v1/consensus", post(post_consensus))
        .route("/p2p/v1/tx", post(post_tx).layer(DefaultBodyLimit::max(256 * 1024)))
        .route("/p2p/v1/status", get(get_status))
        .route("/p2p/v1/block/:height", get(get_block))
        .layer(DefaultBodyLimit::max(wire::MAX_MESSAGE))
        .layer(tower::limit::ConcurrencyLimitLayer::new(16))
        .layer(tower_http::timeout::TimeoutLayer::new(Duration::from_secs(60)))
        // Outermost: refused requests never wait for a concurrency slot.
        .layer(axum::middleware::from_fn_with_state(gate, gatekeeper))
        .with_state(P2p { engine, store, inbox })
}

pub async fn serve(engine: Arc<ConsensusEngine>, store: Arc<BlockStore>, inbox: Inbox, peers: Vec<Peer>, addr: std::net::SocketAddr) -> Result<()> {
    let gate = Arc::new(Gate::new(resolve_peers(&peers), RATE, BURST));
    info!(allowed = ?gate.allowed.read(), "p2p accepts only the validators' addresses");
    let g = gate.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(300));
        tick.tick().await;
        loop {
            tick.tick().await;
            let peers = peers.clone();
            if let Ok(ips) = tokio::task::spawn_blocking(move || resolve_peers(&peers)).await {
                if !ips.is_empty() {
                    g.set_allowed(ips);
                }
            }
        }
    });
    let app = router(engine, store, inbox, gate);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!("BFT p2p listening on http://{addr}/p2p/v1");
    axum::serve(listener, app.into_make_service_with_connect_info::<std::net::SocketAddr>()).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Instant;

    const ME: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));
    const STRANGER: IpAddr = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9));

    #[test]
    fn strangers_are_refused_and_validators_rate_limited() {
        let gate = Gate::new([ME].into(), 10.0, 5.0);
        let t0 = Instant::now();
        assert_eq!(gate.check(STRANGER, t0), Err(StatusCode::FORBIDDEN));
        for _ in 0..5 {
            assert_eq!(gate.check(ME, t0), Ok(()));
        }
        assert_eq!(gate.check(ME, t0), Err(StatusCode::TOO_MANY_REQUESTS));
        // 10 per second: after 0.5 s there is room for 5 again, not 6.
        let t1 = t0 + Duration::from_millis(500);
        for _ in 0..5 {
            assert_eq!(gate.check(ME, t1), Ok(()));
        }
        assert_eq!(gate.check(ME, t1), Err(StatusCode::TOO_MANY_REQUESTS));
        // A changed address list takes effect at once.
        gate.set_allowed([STRANGER].into());
        assert_eq!(gate.check(ME, t1 + Duration::from_secs(9)), Err(StatusCode::FORBIDDEN));
        assert_eq!(gate.check(STRANGER, t1), Ok(()));
    }

    #[test]
    fn peer_urls_resolve_to_their_addresses() {
        let peers = vec![
            Peer { address: Address([1; 32]), url: "http://127.0.0.1:9601".into() },
            Peer { address: Address([2; 32]), url: "http://203.0.113.7:9545".into() },
            Peer { address: Address([3; 32]), url: "not a url".into() },
        ];
        let ips = resolve_peers(&peers);
        assert!(ips.contains(&IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(ips.contains(&ME));
        assert_eq!(ips.len(), 2);
    }

    /// The whole listener: a stranger gets 403 on every route, before
    /// anything else runs; a validator's address gets through.
    #[tokio::test]
    async fn the_listener_only_answers_validators() {
        use axum::extract::connect_info::MockConnectInfo;
        use tower05::ServiceExt;
        let engine = Arc::new(ConsensusEngine::new(
            qtrc_common::genesis::Genesis::testnet_with_faucet(None).initial_state(),
            HydraXKeypair::generate(),
        ));
        let dir = std::env::temp_dir().join(format!("qtrc-gate-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Arc::new(BlockStore::open(dir.to_str().unwrap()).unwrap());
        let (tx, _rx) = mpsc::sync_channel(4);
        let gate = Arc::new(Gate::new([ME].into(), RATE, BURST));
        let app = router(engine, store, Inbox(tx), gate);
        let get = |ip: IpAddr| {
            let app = app.clone().layer(MockConnectInfo(std::net::SocketAddr::new(ip, 40000)));
            async move {
                let req = axum::http::Request::get("/p2p/v1/status").body(axum::body::Body::empty()).unwrap();
                app.oneshot(req).await.unwrap().status()
            }
        };
        assert_eq!(get(STRANGER).await, StatusCode::FORBIDDEN);
        assert_eq!(get(ME).await, StatusCode::OK);
        let req = axum::http::Request::post("/p2p/v1/consensus").body(axum::body::Body::from(vec![0u8; 1024])).unwrap();
        let app2 = app.clone().layer(MockConnectInfo(std::net::SocketAddr::new(STRANGER, 1)));
        assert_eq!(app2.oneshot(req).await.unwrap().status(), StatusCode::FORBIDDEN);
        std::fs::remove_dir_all(&dir).ok();
    }
}
