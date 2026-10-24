//! JSON-RPC HTTP server.
//!
//! Endpoints:
//!   GET  /status               → node status
//!   GET  /block/:height        → block by height
//!   GET  /account/:address     → account balance + nonce
//!   GET  /vault/:address       → Sentinel vault of an account
//!   GET  /proof/:address       → state proof + the signed header it verifies against
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
use serde::Serialize;
use std::{net::SocketAddr, sync::Arc};
use tower_http::cors::{Any, CorsLayer};
use tracing::info;

#[derive(Clone)]
struct AppState {
    engine: Arc<ConsensusEngine>,
    store:  Arc<crate::store::BlockStore>,
    /// Follower nodes do not take transactions: they produce no blocks.
    follower: bool,
    /// BFT validator: pass accepted transactions to the other validators.
    relay: Option<crate::bft::Outbox>,
}

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
    /// Fee the next block charges per tx, in micro-QTR (burned)
    fee:          u64,
    /// Total micro-QTR burned in fees so far
    burned:       u64,
    /// First block that accepts Sentinel operations
    sentinel_from_height: u64,
    /// First block whose header carries the state root
    state_root_from_height: u64,
    /// First block whose header commits to full transactions
    witness_root_from_height: u64,
    /// "validator" or "follower"
    role: &'static str,
}

#[derive(Serialize)]
struct AccountResponse {
    address: String,
    balance: u64,
    /// Nonce of the last confirmed state
    nonce:   u64,
    /// Nonce the next transaction must use (counts pending txs too)
    next_nonce: u64,
}

#[derive(Serialize)]
struct VaultResponse {
    address:   String,
    /// Spendable now (balance minus reserved)
    available: u64,
    vault:     qtrc_sentinel::Vault,
}

#[derive(Serialize)]
struct ProofResponse {
    /// Block whose header commits to the state this proof was built from
    header:         qtrc_common::block::BlockHeader,
    /// That block's validator signatures (verify the proposer's over
    /// `header.signing_bytes()`)
    validator_sigs: Vec<qtrc_common::block::ValidatorSig>,
    /// Inclusion proof; null if the account is empty
    proof:          Option<qtrc_common::state_root::Proof>,
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

async fn get_status(State(AppState { engine, follower, .. }): State<AppState>) -> Json<StatusResponse> {
    let role = if follower { "follower" } else { "validator" };
    let state = engine.state.read();
    Json(StatusResponse {
        chain_id:     qtrc_common::tx::CHAIN_ID,
        height:       state.height,
        block_hash:   state.block_hash.to_string(),
        node_address: engine.address.to_string(),
        version:      env!("CARGO_PKG_VERSION"),
        fee:          state.fee_at(state.height + 1),
        burned:       state.burned,
        sentinel_from_height: state.sentinel_from_height,
        state_root_from_height: state.state_root_from_height,
        witness_root_from_height: state.witness_root_from_height,
        role,
    })
}

async fn get_account(
    State(AppState { engine, .. }): State<AppState>,
    Path(address): Path<String>,
) -> Result<Json<AccountResponse>, (StatusCode, Json<ErrorResponse>)> {
    let addr = qtrc_crypto::Address::from_hex(&address).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse { error: e.to_string() }),
        )
    })?;

    let acct = engine.state.read().account(&addr);
    let next_nonce = engine.next_nonce(&addr);

    Ok(Json(AccountResponse {
        address: addr.as_hex(),
        balance: acct.balance,
        nonce:   acct.nonce,
        next_nonce,
    }))
}

async fn get_vault(
    State(AppState { engine, .. }): State<AppState>,
    Path(address): Path<String>,
) -> Result<Json<VaultResponse>, (StatusCode, Json<ErrorResponse>)> {
    let addr = qtrc_crypto::Address::from_hex(&address).map_err(|e| {
        (StatusCode::BAD_REQUEST, Json(ErrorResponse { error: e.to_string() }))
    })?;
    let state = engine.state.read();
    let vault = state.vault(&addr).cloned().ok_or_else(|| {
        (StatusCode::NOT_FOUND, Json(ErrorResponse { error: "account has no Sentinel vault".into() }))
    })?;
    Ok(Json(VaultResponse { address: addr.as_hex(), available: vault.available(), vault }))
}

async fn get_proof(
    State(AppState { engine, .. }): State<AppState>,
    Path(address): Path<String>,
) -> Result<Json<ProofResponse>, (StatusCode, Json<ErrorResponse>)> {
    let addr = qtrc_crypto::Address::from_hex(&address).map_err(|e| {
        (StatusCode::BAD_REQUEST, Json(ErrorResponse { error: e.to_string() }))
    })?;
    // Building the proof walks every account: keep it off the async runtime.
    let result = tokio::task::spawn_blocking(move || engine.state_proof(&addr))
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: e.to_string() })))?;
    match result {
        Ok((header, validator_sigs, proof)) => Ok(Json(ProofResponse { header, validator_sigs, proof })),
        Err(e) => Err((StatusCode::CONFLICT, Json(ErrorResponse { error: e.to_string() }))),
    }
}

/// A stored block, as committed: anyone can replay the chain from these and
/// check every header, signature, state root and witness root.
async fn get_block(
    State(app): State<AppState>,
    Path(height): Path<u64>,
) -> Result<Json<qtrc_common::block::Block>, (StatusCode, Json<ErrorResponse>)> {
    let store = app.store.clone();
    let found = tokio::task::spawn_blocking(move || store.get_block(height))
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: e.to_string() })))?
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: e.to_string() })))?;
    found.map(Json).ok_or_else(|| (StatusCode::NOT_FOUND, Json(ErrorResponse { error: format!("no block at height {height}") })))
}

async fn post_tx(
    State(AppState { engine, follower, relay, .. }): State<AppState>,
    Json(tx): Json<Transaction>,
) -> Result<Json<TxResponse>, (StatusCode, Json<ErrorResponse>)> {
    if follower {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorResponse { error: "this node is a follower and produces no blocks; send transactions to a validator".into() }),
        ));
    }
    // HYDRA-X verification is CPU work (~2.6 ms); run it off the async
    // runtime so status and account queries stay fast under load.
    let relayed = tx.clone();
    let result = tokio::task::spawn_blocking(move || engine.submit_tx(tx))
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: format!("verification task failed: {e}") }),
            )
        })?;
    match result {
        Ok(hash) => Ok(Json({
            if let Some(r) = &relay {
                r.relay_tx(&relayed);
            }
            TxResponse {
            tx_hash: hash.to_string(),
        }})),
        Err(e @ qtrc_consensus::ConsensusError::Busy(_)) => Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorResponse { error: e.to_string() }),
        )),
        Err(e) => Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse { error: e.to_string() }),
        )),
    }
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub async fn serve(engine: Arc<ConsensusEngine>, store: Arc<crate::store::BlockStore>, follower: bool, relay: Option<crate::bft::Outbox>, addr: SocketAddr) {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let app = Router::new()
        .route("/status",           get(get_status))
        .route("/block/:height",    get(get_block))
        .route("/account/:address", get(get_account))
        .route("/vault/:address",   get(get_vault))
        .route("/proof/:address",   get(get_proof))
        .route("/tx",               post(post_tx))
        .layer(cors)
        .with_state(AppState { engine, store, follower, relay });

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("RPC bind failed");

    info!("RPC server ready");
    axum::serve(listener, app).await.expect("RPC server error");
}
