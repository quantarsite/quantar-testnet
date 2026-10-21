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
use tracing::{info, warn};

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

#[derive(Parser, Debug)]
#[command(
    name    = "qtrc-node",
    version,
    about   = "Quantar Network testnet node — HYDRA-X post-quantum consensus"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Generate a new HYDRA-X keypair, save it to a key file and print the address
    Keygen {
        /// Where to write the key file (created with owner-only permissions)
        #[arg(long)]
        out: String,
    },
    /// Start the node
    Start {
        /// JSON-RPC listen address
        /// Local by default: expose it through a reverse proxy with limits
        /// (see deploy/nginx), never directly on 0.0.0.0
        #[arg(long, default_value = "127.0.0.1:8545")]
        rpc: String,
        /// Data directory
        #[arg(long, default_value = "./qtrc-data")]
        data_dir: String,
        /// Validator key file from `qtrc-node keygen --out`. Without it the
        /// node generates a throwaway key and its address changes on restart.
        #[arg(long)]
        key_file: Option<String>,
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
        Command::Keygen { out } => cmd_keygen(&out)?,
        Command::Start { rpc, data_dir, key_file } => cmd_start(rpc, data_dir, key_file).await?,
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// keygen
// ---------------------------------------------------------------------------

fn cmd_keygen(out: &str) -> Result<()> {
    let keypair = HydraXKeypair::generate();
    let address = keypair.address();
    write_secret_file(out, &keypair.to_bytes())?;
    println!("HYDRA-X v2 keypair generated");
    println!("Address : {}", address.as_hex());
    println!("Short   : {address}");
    println!("Key file: {out}");
    println!();
    println!("Keep this file secret and backed up. Anyone with it can sign as this address.");
    Ok(())
}

/// Write `bytes` to `path`, refusing to overwrite, with mode 0600 on Unix.
fn write_secret_file(path: &str, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts
        .open(path)
        .map_err(|e| anyhow::anyhow!("cannot create key file {path}: {e} (it will not overwrite an existing file)"))?;
    f.write_all(bytes)?;
    f.sync_all()?;
    Ok(())
}

fn load_keypair(path: &str) -> Result<HydraXKeypair> {
    let bytes = zeroize::Zeroizing::new(
        std::fs::read(path).map_err(|e| anyhow::anyhow!("cannot read key file {path}: {e}"))?,
    );
    HydraXKeypair::from_bytes(&bytes).map_err(|e| anyhow::anyhow!("invalid key file {path}: {e}"))
}

// ---------------------------------------------------------------------------
// start
// ---------------------------------------------------------------------------

async fn cmd_start(rpc_addr: String, data_dir: String, key_file: Option<String>) -> Result<()> {
    let keypair = match key_file {
        Some(path) => {
            info!("🔑 Loading HYDRA-X validator key from {path}");
            load_keypair(&path)?
        }
        None => {
            warn!("🔑 No --key-file given: generating a throwaway HYDRA-X key for this run");
            HydraXKeypair::generate()
        }
    };
    let address = keypair.address();
    info!("Node address: {} ({address})", address.as_hex());

    // Open the chain store first: an existing data directory decides the
    // genesis, so a restart can never silently start a different chain.
    let store = Arc::new(store::BlockStore::open(&data_dir)?);
    let env_genesis = Genesis::testnet();
    let genesis = match store.genesis()? {
        Some(saved) => {
            if serde_json::to_value(&saved)? != serde_json::to_value(&env_genesis)? {
                warn!(
                    "QTR_FAUCET_ADDRESS differs from the genesis saved in {data_dir}; \
                     keeping the saved genesis (start with a new --data-dir for a new chain)"
                );
            }
            saved
        }
        None => {
            store.save_genesis(&env_genesis)?;
            info!("New data directory: genesis saved to {data_dir}");
            env_genesis
        }
    };

    if genesis.chain_id != qtrc_common::tx::CHAIN_ID {
        anyhow::bail!(
            "data directory belongs to chain {}, this binary runs {}. Use a new --data-dir.",
            genesis.chain_id,
            qtrc_common::tx::CHAIN_ID
        );
    }

    let mut init_state = genesis.initial_state();
    init_state.fee_from_height = store.fee_from_height()?;
    init_state.sentinel_from_height = store.sentinel_from_height()?;
    info!(
        sentinel_from_height = init_state.sentinel_from_height,
        "Sentinel operations accepted from this height"
    );
    info!(
        fee_from_height = init_state.fee_from_height,
        fee_micro_qtr = qtrc_common::tx::TX_FEE,
        "Protocol fee (burned) active from this height"
    );
    info!(
        chain_id  = %genesis.chain_id,
        accounts  = init_state.accounts.len(),
        "Genesis state loaded"
    );
    if genesis.allocations.is_empty() {
        warn!("genesis has no faucet allocation (QTR_FAUCET_ADDRESS was not set when this chain was created)");
    }

    // Build consensus engine with durable block storage
    let engine = Arc::new(ConsensusEngine::new(init_state, keypair).with_sink(store.clone()));

    // Rebuild state by re-verifying and re-applying every stored block
    let mut replayed = 0u64;
    for block in store.blocks() {
        let block = block?;
        let height = block.header.height;
        engine
            .replay_block(block)
            .map_err(|e| anyhow::anyhow!("stored block {height} failed replay: {e}"))?;
        replayed += 1;
    }
    {
        let state = engine.state.read();
        info!(height = state.height, replayed, "Chain state restored from disk");
    }

    // Stop accepting transactions before the disk fills up, so a spam wave
    // stalls the testnet instead of breaking the server and its other sites.
    let guard_engine = engine.clone();
    let guard_dir = data_dir.clone();
    tokio::spawn(async move {
        const MIN_FREE: u64 = 2 * 1024 * 1024 * 1024; // 2 GiB
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(30));
        loop {
            tick.tick().await;
            match fs2::available_space(&guard_dir) {
                Ok(free) => {
                    let ok = free >= MIN_FREE;
                    if ok != guard_engine.is_accepting() {
                        if ok {
                            info!(free_mib = free / 1_048_576, "disk space recovered: accepting transactions again");
                        } else {
                            warn!(free_mib = free / 1_048_576, "low disk space: refusing new transactions");
                        }
                        guard_engine.set_accepting(ok);
                    }
                }
                Err(e) => warn!("could not check free disk space: {e}"),
            }
        }
    });

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
