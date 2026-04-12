//! # qtrc-node
//!
//! Quantar Network testnet node.
//! Starts the consensus engine, JSON-RPC HTTP server, and
//! (future) P2P listener.

mod rpc;
mod store;

use anyhow::Result;
use clap::{Parser, Subcommand};
use qtrc_common::genesis::Genesis;
use qtrc_consensus::{run_block_producer, ConsensusEngine};
use qtrc_crypto::HydraXKeypair;
use std::sync::Arc;
use tracing::info;

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

#[derive(Parser, Debug)]
#[command(
    name    = "qtrc-node",
    version = "0.1.0",
    about   = "Quantar Network testnet node — HYDRA-X post-quantum consensus"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Generate a new HYDRA-X keypair and print the address
    Keygen,
    /// Start the node
    Start {
        /// JSON-RPC listen address
        #[arg(long, default_value = "0.0.0.0:8545")]
        rpc: String,
        /// Data directory
        #[arg(long, default_value = "./qtrc-data")]
        data_dir: String,
    },
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("qtrc=debug".parse()?),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Command::Keygen => cmd_keygen(),
        Command::Start { rpc, data_dir } => cmd_start(rpc, data_dir).await?,
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// keygen
// ---------------------------------------------------------------------------

fn cmd_keygen() {
    let keypair = HydraXKeypair::generate();
    let address = keypair.address();
    println!("HYDRA-X keypair generated");
    println!("Address : {address}");
    println!();
    println!("⚠️  Save the verifying key bytes to disk before exiting.");
    println!("   Production key management coming in a future release.");
}

// ---------------------------------------------------------------------------
// start
// ---------------------------------------------------------------------------

async fn cmd_start(rpc_addr: String, data_dir: String) -> Result<()> {
    info!("🔑 Generating ephemeral HYDRA-X keypair for this node...");
    info!("   (persistent key storage coming in next release)");

    let keypair = HydraXKeypair::generate();
    let address = keypair.address();
    info!("Node address: {address}");

    // Load or create genesis
    let genesis    = Genesis::testnet();
    let init_state = genesis.initial_state();

    info!(
        chain_id  = %genesis.chain_id,
        height    = init_state.height,
        accounts  = init_state.accounts.len(),
        "Genesis state loaded"
    );

    // Open persistent store
    let _store = store::BlockStore::open(&data_dir)?;

    // Build consensus engine
    let engine = Arc::new(ConsensusEngine::new(init_state, keypair));

    // Spawn block producer
    let engine_clone = engine.clone();
    tokio::spawn(async move {
        run_block_producer(engine_clone).await;
    });

    // Start JSON-RPC server
    info!("JSON-RPC listening on http://{rpc_addr}");
    rpc::serve(engine, rpc_addr.parse()?).await;

    Ok(())
}
