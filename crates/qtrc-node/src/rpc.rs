//! JSON-RPC HTTP server.
//!
//! Endpoints:
//!   GET  /status               → node status
//!   GET  /block/:height        → block by height
//!   GET  /account/:address     → account balance + nonce
//!   POST /tx                   → submit a signed transaction

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Router,
};
use qtrc_common::tx::Transaction;
use qtrc_consensus::ConsensusEngine;
use serde::{Deserialize, Serialize};
use std::{net::SocketAddr, sync::Arc};
use tower_http::cors::{Any, CorsLayer};
use tracing::info;

type AppState = Arc<ConsensusEngine>;

// ---------------------------------------------------------------------------
// Response types
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct StatusResponse {
    chain_id:     &'static str,
    height:       u64,
    block_hash:   String,
    node_address: String,
    version:      &'static str,
}

#[derive(Serialize)]
struct AccountResponse {
    address: String,
    balance: u64,
    nonce:   u64,
}

#[derive(Serialize)]
struct TxResponse {
    tx_hash: String,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

async fn get_status(State(engine): State<AppState>) -> Json<StatusResponse> {
    let state = engine.state.read();
    Json(StatusResponse {
        chain_id:     "quantar-testnet-1",
        height:       state.height,
        block_hash:   state.block_hash.to_string(),
        node_address: engine.address.to_string(),
        version:      env!("CARGO_PKG_VERSION"),
    })
}

async fn get_account(
    State(engine): State<AppState>,
    Path(address): Path<String>,
) -> Result<Json<AccountResponse>, (StatusCode, Json<ErrorResponse>)> {
    let addr = qtrc_crypto::Address::from_hex(&address).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse { error: e.to_string() }),
        )
    })?;

    let state = engine.state.read();
    let acct  = state.account(&addr);

    Ok(Json(AccountResponse {
        address: address,
        balance: acct.balance,
        nonce:   acct.nonce,
    }))
}

async fn post_tx(
    State(engine): State<AppState>,
    Json(tx): Json<Transaction>,
) -> Result<Json<TxResponse>, (StatusCode, Json<ErrorResponse>)> {
    match engine.submit_tx(tx) {
        Ok(hash) => Ok(Json(TxResponse {
            tx_hash: hash.to_string(),
        })),
        Err(e) => Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse { error: e.to_string() }),
        )),
    }
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub async fn serve(engine: Arc<ConsensusEngine>, addr: SocketAddr) {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let app = Router::new()
        .route("/status",           get(get_status))
        .route("/account/:address", get(get_account))
        .route("/tx",               post(post_tx))
        .layer(cors)
        .with_state(engine);

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("RPC bind failed");

    info!("RPC server ready");
    axum::serve(listener, app).await.expect("RPC server error");
}
