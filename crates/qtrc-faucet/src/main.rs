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
use qtrc_crypto::Address;
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

    /// Faucet wallet address (must be funded in genesis)
    #[arg(long)]
    faucet_address: String,
}

// ---------------------------------------------------------------------------
// App state
// ---------------------------------------------------------------------------

struct FaucetState {
    /// address hex → last drip time
    rate_limits: DashMap<String, DateTime<Utc>>,
    node_rpc:    String,
    faucet_addr: String,
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
    let _addr = Address::from_hex(&req.address).map_err(|_| {
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

    // Forward drip request to node RPC
    // (In a full impl the faucet would sign a tx with its keypair
    //  and POST to /tx. For testnet v1 we call a dedicated faucet endpoint.)
    let drip_payload = serde_json::json!({
        "from":      state.faucet_addr,
        "to":        req.address,
        "amount":    DRIP_AMOUNT,
    });

    let resp = state
        .http
        .post(format!("{}/faucet/drip", state.node_rpc))
        .json(&drip_payload)
        .send()
        .await
        .map_err(|e| {
            warn!("node RPC error: {e}");
            (
                StatusCode::BAD_GATEWAY,
                Json(ErrorResponse {
                    error: "node unreachable — try again later".into(),
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

    let state = Arc::new(FaucetState {
        rate_limits: DashMap::new(),
        node_rpc:    cli.node_rpc,
        faucet_addr: cli.faucet_address,
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
