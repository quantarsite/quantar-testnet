//! # qtrc-faucet
//!
//! HTTP faucet for the Quantar testnet.
//! Sends 100 QTR to any address — once per address per hour.
//!
//! POST /faucet
//!   Body: { "address": "<hex>" }
//!   Response: { "tx_hash": "..." } | { "error": "..." }

use axum::{
    extract::State,
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
use std::{net::SocketAddr, sync::Arc};
use tracing::{info, warn};

/// 100 QTR drip per request
const DRIP_AMOUNT: u64 = 100 * MICRO_QTR;
/// Minimum seconds between drips to the same address
const RATE_LIMIT_SECS: i64 = 3600;

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
    /// address hex → last drip time
    rate_limits: DashMap<String, DateTime<Utc>>,
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
    Json(req): Json<FaucetRequest>,
) -> Result<Json<FaucetResponse>, (StatusCode, Json<ErrorResponse>)> {
    // Validate address
    let to_addr = Address::from_hex(&req.address).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "invalid address — expected 32-byte hex string".into(),
            }),
        )
    })?;

    let key = req.address.to_lowercase();

    // Rate limit check
    if let Some(last) = state.rate_limits.get(&key) {
        let elapsed = Utc::now() - *last;
        if elapsed < Duration::seconds(RATE_LIMIT_SECS) {
            let wait = RATE_LIMIT_SECS - elapsed.num_seconds();
            return Err((
                StatusCode::TOO_MANY_REQUESTS,
                Json(ErrorResponse {
                    error: format!("rate limited — try again in {wait}s"),
                }),
            ));
        }
    }

    // Build and sign a real HYDRA-X transaction from the faucet wallet.
    // The nonce lock covers fetch, sign and submit so drips stay ordered.
    let mut next_nonce = state.next_nonce.lock().await;

    let chain_nonce = fetch_nonce(&state).await.map_err(|e| {
        warn!("node RPC error: {e}");
        (
            StatusCode::BAD_GATEWAY,
            Json(ErrorResponse {
                error: "node unreachable, try again later".into(),
            }),
        )
    })?;
    let nonce = chain_nonce.max(*next_nonce);

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

    // Update rate limit
    state.rate_limits.insert(key, Utc::now());

    info!(to = %req.address, amount = DRIP_AMOUNT, "💧 drip sent");

    Ok(Json(FaucetResponse {
        tx_hash,
        amount:  DRIP_AMOUNT,
        message: format!("Sent {} µQTR (100 QTR) to {}", DRIP_AMOUNT, req.address),
    }))
}

/// Current on-chain nonce of the faucet wallet.
async fn fetch_nonce(state: &FaucetState) -> anyhow::Result<u64> {
    let v: serde_json::Value = state
        .http
        .get(format!("{}/account/{}", state.node_rpc, state.faucet_addr.as_hex()))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    v["nonce"].as_u64().ok_or_else(|| anyhow::anyhow!("account response without nonce"))
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

    let bytes = std::fs::read(&cli.key_file)?;
    let keypair = HydraXKeypair::from_bytes(&bytes)
        .map_err(|e| anyhow::anyhow!("invalid faucet key file {}: {e}", cli.key_file))?;
    let faucet_addr = keypair.address();
    info!("💧 Faucet wallet: {}", faucet_addr.as_hex());

    let state = Arc::new(FaucetState {
        rate_limits: DashMap::new(),
        node_rpc:    cli.node_rpc,
        keypair,
        faucet_addr,
        next_nonce:  tokio::sync::Mutex::new(0),
        http:        Client::new(),
    });

    let app = Router::new()
        .route("/faucet", post(handle_faucet))
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
    axum::serve(listener, app).await?;

    Ok(())
}
