//! # qtrc-faucet
//!
//! HTTP faucet for the Quantar testnet.
//! Sends 50 QTR per request, once per address and once per IP per hour,
//! with a global cap per hour.
//!
//! POST /faucet
//!   Body: { "address": "<hex>" }
//!   Response: { "tx_hash": "..." } | { "error": "..." }

use axum::{
    extract::{ConnectInfo, State},
    http::HeaderMap,
    http::StatusCode,
    response::Json,
    routing::post,
    Router,
};
use chrono::{DateTime, Duration, Utc};
use clap::Parser;
use dashmap::DashMap;
use qtrc_common::genesis::MICRO_QTR;
use qtrc_common::tx::Transaction;
use qtrc_crypto::{Address, HydraXKeypair};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::{
    collections::VecDeque,
    net::{IpAddr, SocketAddr},
    sync::Arc,
};
use tracing::{info, warn};

/// 50 QTR drip per request
const DRIP_AMOUNT: u64 = 50 * MICRO_QTR;
/// Minimum seconds between drips to the same address, and from the same IP
const RATE_LIMIT_SECS: i64 = 3600;
/// Hard cap on drips across all clients per rolling hour (5.000 QTR/h).
/// Even a botnet with many IPs cannot drain faster than this.
const GLOBAL_MAX_PER_HOUR: usize = 100;
/// How often stale rate-limit entries are purged from memory
const CLEANUP_EVERY_SECS: u64 = 600;

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

#[derive(Parser, Debug)]
#[command(name = "qtrc-faucet", about = "Quantar testnet faucet")]
struct Cli {
    /// Faucet HTTP listen address
    #[arg(long, default_value = "0.0.0.0:8546")]
    listen: String,

    /// Node RPC URL to submit transactions
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    node_rpc: String,

    /// Faucet key file from `qtrc-node keygen --out`. Its address must be
    /// the one funded in genesis (QTR_FAUCET_ADDRESS on the node).
    #[arg(long)]
    key_file: String,
}

// ---------------------------------------------------------------------------
// App state
// ---------------------------------------------------------------------------

struct FaucetState {
    /// "addr:<hex>" or "ip:<ip>" → last drip time
    rate_limits: DashMap<String, DateTime<Utc>>,
    /// Times of recent drips, for the global hourly cap
    recent_drips: tokio::sync::Mutex<VecDeque<DateTime<Utc>>>,
    node_rpc:    String,
    keypair:     HydraXKeypair,
    faucet_addr: Address,
    /// Next nonce to use; guarded so concurrent drips never reuse a nonce.
    next_nonce:  tokio::sync::Mutex<u64>,
    http:        Client,
}

// ---------------------------------------------------------------------------
// Request / response types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct FaucetRequest {
    address: String,
}

#[derive(Serialize)]
struct FaucetResponse {
    tx_hash: String,
    amount:  u64,
    message: String,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

async fn handle_faucet(
    State(state): State<Arc<FaucetState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<FaucetRequest>,
) -> Result<Json<FaucetResponse>, (StatusCode, Json<ErrorResponse>)> {
    // Validate address
    let to_addr = parse_address(&req.address).map_err(|error| {
        (StatusCode::BAD_REQUEST, Json(ErrorResponse { error }))
    })?;

    let addr_key = format!("addr:{}", to_addr.as_hex());
    let ip_key = format!("ip:{}", client_ip(peer, &headers));

    // Every drip is serialized by the nonce lock, so the rate-limit checks
    // below and the inserts after a successful submit cannot race.
    let mut next_nonce = state.next_nonce.lock().await;
    let now = Utc::now();

    for key in [&addr_key, &ip_key] {
        if let Some(wait) = seconds_left(&state.rate_limits, key, now) {
            return Err(limited(format!("rate limited, try again in {wait}s")));
        }
    }

    let mut recent = state.recent_drips.lock().await;
    while recent.front().is_some_and(|t| now - *t >= Duration::seconds(3600)) {
        recent.pop_front();
    }
    if recent.len() >= GLOBAL_MAX_PER_HOUR {
        return Err(limited("faucet is busy, hourly limit reached, try again later".into()));
    }

    // Build and sign a real HYDRA-X transaction from the faucet wallet.
    let chain_nonce = fetch_nonce(&state).await.map_err(|e| {
        warn!("node RPC error: {e}");
        (
            StatusCode::BAD_GATEWAY,
            Json(ErrorResponse {
                error: "node unreachable, try again later".into(),
            }),
        )
    })?;
    // The node counts our pending txs, so its answer is authoritative.
    // (A local counter could run ahead of the chain if a tx were dropped.)
    let nonce = chain_nonce;

    let payload = Transaction::signing_payload(&state.faucet_addr, &to_addr, DRIP_AMOUNT, nonce);
    let tx = Transaction {
        from:      state.faucet_addr.clone(),
        to:        to_addr,
        amount:    DRIP_AMOUNT,
        nonce,
        timestamp: Utc::now().timestamp(),
        signature: state.keypair.sign(&payload),
    };

    let resp = state
        .http
        .post(format!("{}/tx", state.node_rpc))
        .json(&tx)
        .send()
        .await
        .map_err(|e| {
            warn!("node RPC error: {e}");
            (
                StatusCode::BAD_GATEWAY,
                Json(ErrorResponse {
                    error: "node unreachable, try again later".into(),
                }),
            )
        })?;

    if !resp.status().is_success() {
        let err: serde_json::Value = resp.json().await.unwrap_or_default();
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: err["error"].as_str().unwrap_or("node error").into(),
            }),
        ));
    }
    *next_nonce = nonce + 1;
    drop(next_nonce);

    let result: serde_json::Value = resp.json().await.map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: "invalid node response".into() }),
        )
    })?;

    let tx_hash = result["tx_hash"].as_str().unwrap_or("pending").to_string();

    // Record the drip only after the node accepted it.
    state.rate_limits.insert(addr_key, now);
    state.rate_limits.insert(ip_key, now);
    recent.push_back(now);
    drop(recent);

    info!(to = %req.address, amount = DRIP_AMOUNT, "💧 drip sent");

    Ok(Json(FaucetResponse {
        tx_hash,
        amount:  DRIP_AMOUNT,
        message: format!("Sent {} µQTR ({} QTR) to {}", DRIP_AMOUNT, DRIP_AMOUNT / MICRO_QTR, req.address),
    }))
}

/// Parse a full Quantar address, with a clear message for the usual mistakes.
fn parse_address(input: &str) -> Result<Address, String> {
    let a = input.trim();
    if a.starts_with("qtr1") {
        return Err("That is the short display form of an address (qtr1...), which is only half \
                    of it. Paste the full 64-character address printed by `qtrc-node keygen`."
            .into());
    }
    if a.starts_with("0x") || a.starts_with("bc1") || a.starts_with('1') && a.len() < 40 {
        return Err("Quantar does not use ECDSA, so Ethereum, Bitcoin and Solana wallets cannot \
                    receive QTR. Generate a post-quantum address with `qtrc-node keygen`."
            .into());
    }
    let looks_hex = a.len() == 64 && a.bytes().all(|b| b.is_ascii_hexdigit());
    if !looks_hex {
        return Err("Invalid address. A Quantar address is 64 hex characters, as printed by \
                    `qtrc-node keygen`."
            .into());
    }
    Address::from_hex(&a.to_lowercase()).map_err(|_| "Invalid address.".to_string())
}

/// Real client IP. Behind nginx on the same host the TCP peer is loopback,
/// so the proxy headers are trusted only in that case; a remote client
/// cannot spoof its IP by sending X-Forwarded-For itself.
fn client_ip(peer: SocketAddr, headers: &HeaderMap) -> IpAddr {
    if peer.ip().is_loopback() {
        let from_header = headers
            .get("x-real-ip")
            .or_else(|| headers.get("x-forwarded-for"))
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(',').next())
            .and_then(|v| v.trim().parse::<IpAddr>().ok());
        if let Some(ip) = from_header {
            return ip;
        }
    }
    peer.ip()
}

/// Seconds until `key` may drip again, or None if it may drip now.
fn seconds_left(map: &DashMap<String, DateTime<Utc>>, key: &str, now: DateTime<Utc>) -> Option<i64> {
    let last = *map.get(key)?;
    let elapsed = now - last;
    (elapsed < Duration::seconds(RATE_LIMIT_SECS)).then(|| RATE_LIMIT_SECS - elapsed.num_seconds())
}

fn limited(error: String) -> (StatusCode, Json<ErrorResponse>) {
    (StatusCode::TOO_MANY_REQUESTS, Json(ErrorResponse { error }))
}

/// Nonce for the faucet's next transaction (on-chain nonce plus pending).
async fn fetch_nonce(state: &FaucetState) -> anyhow::Result<u64> {
    let v: serde_json::Value = state
        .http
        .get(format!("{}/account/{}", state.node_rpc, state.faucet_addr.as_hex()))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    v["next_nonce"]
        .as_u64()
        .or_else(|| v["nonce"].as_u64())
        .ok_or_else(|| anyhow::anyhow!("account response without nonce"))
}

// ---------------------------------------------------------------------------
// Website API (faucet.quantarnetwork.com/api/*)
// ---------------------------------------------------------------------------
//
// The public page reads `success`, `message`, `amount` (in QTR) and `tx_hash`
// from /api/claim, and `online`, `claim_amount`, `cooldown_hours`,
// `total_claims`, `network` from /api/status.

#[derive(Serialize)]
struct ApiClaimResponse {
    success: bool,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    amount:  Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tx_hash: Option<String>,
}

async fn api_claim(
    state: State<Arc<FaucetState>>,
    peer: ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    req: Json<FaucetRequest>,
) -> (StatusCode, Json<ApiClaimResponse>) {
    match handle_faucet(state, peer, headers, req).await {
        Ok(Json(ok)) => (
            StatusCode::OK,
            Json(ApiClaimResponse {
                success: true,
                message: format!("Sent {} QTR.", ok.amount / MICRO_QTR),
                amount:  Some(ok.amount / MICRO_QTR),
                tx_hash: Some(ok.tx_hash),
            }),
        ),
        Err((code, Json(err))) => (
            code,
            Json(ApiClaimResponse { success: false, message: err.error, amount: None, tx_hash: None }),
        ),
    }
}

#[derive(Serialize)]
struct ApiStatusResponse {
    online:         bool,
    claim_amount:   u64,
    cooldown_hours: i64,
    /// Every claim is one signed transaction from the faucet wallet, so the
    /// wallet's on-chain nonce is the claim count. Survives restarts.
    total_claims:   u64,
    network:        String,
}

async fn api_status(State(state): State<Arc<FaucetState>>) -> Json<ApiStatusResponse> {
    let nonce = fetch_nonce(&state).await;
    Json(ApiStatusResponse {
        online:         nonce.is_ok(),
        claim_amount:   DRIP_AMOUNT / MICRO_QTR,
        cooldown_hours: RATE_LIMIT_SECS / 3600,
        total_claims:   nonce.unwrap_or(0),
        network:        qtrc_common::tx::CHAIN_ID.to_string(),
    })
}

// ---------------------------------------------------------------------------
// Health check
// ---------------------------------------------------------------------------

async fn health() -> &'static str {
    "quantar faucet ok"
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().init();

    let cli = Cli::parse();

    let bytes = zeroize::Zeroizing::new(std::fs::read(&cli.key_file)?);
    let keypair = HydraXKeypair::from_bytes(&bytes)
        .map_err(|e| anyhow::anyhow!("invalid faucet key file {}: {e}", cli.key_file))?;
    let faucet_addr = keypair.address();
    info!("💧 Faucet wallet: {}", faucet_addr.as_hex());

    let state = Arc::new(FaucetState {
        rate_limits: DashMap::new(),
        recent_drips: tokio::sync::Mutex::new(VecDeque::new()),
        node_rpc:    cli.node_rpc,
        keypair,
        faucet_addr,
        next_nonce:  tokio::sync::Mutex::new(0),
        http:        Client::new(),
    });

    // Purge expired rate-limit entries so the map cannot grow forever.
    let cleaner = state.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(CLEANUP_EVERY_SECS));
        loop {
            tick.tick().await;
            let cutoff = Utc::now() - Duration::seconds(RATE_LIMIT_SECS);
            cleaner.rate_limits.retain(|_, t| *t > cutoff);
        }
    });

    let app = Router::new()
        .route("/faucet", post(handle_faucet))
        .route("/api/claim", post(api_claim))
        .route("/api/status", axum::routing::get(api_status))
        .route("/health", axum::routing::get(health))
        .layer(
            tower_http::cors::CorsLayer::new()
                .allow_origin(tower_http::cors::Any)
                .allow_methods(tower_http::cors::Any)
                .allow_headers(tower_http::cors::Any),
        )
        .with_state(state);

    let addr: SocketAddr = cli.listen.parse()?;
    info!("💧 Faucet listening on http://{addr}");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await?;

    Ok(())
}
