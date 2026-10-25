//! # qtrc-node
//!
//! Quantar Network testnet node.
//! Starts the consensus engine, JSON-RPC HTTP server, and
//! (future) P2P listener.

mod bft;
mod follow;
mod p2p;
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
        /// node uses `<data-dir>/node.key`, created on first start, so its
        /// address stays the same across restarts.
        #[arg(long)]
        key_file: Option<String>,
        /// Follow these nodes instead of producing blocks: download every
        /// block from them, verify it fully and store it. Repeat for more
        /// peers, e.g. --follow https://testnet.quantarnetwork.com/rpc
        #[arg(long)]
        follow: Vec<String>,
        /// Validator whose signature blocks must carry, for chains whose
        /// validator is not fixed in the code (the live network's is).
        #[arg(long)]
        validator: Option<String>,
        /// Listen for block announcements from validators on this address,
        /// e.g. 0.0.0.0:9545 on a follower. Only that one route is served
        /// there. Off by default.
        #[arg(long)]
        p2p: Option<String>,
        /// Tell these nodes about every new block right after committing it
        /// (their --p2p address, e.g. http://203.0.113.7:9545). Repeatable.
        #[arg(long)]
        announce_to: Vec<String>,
        /// Run with several validators deciding blocks by vote (BFT), on a
        /// network not fixed in code: a JSON file with `bft_from_height`
        /// and `validators` [{address, p2p}]. Validators listed there need
        /// --p2p; anyone else runs as a follower (--follow).
        #[arg(long)]
        bft_config: Option<String>,
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
        Command::Start { rpc, data_dir, key_file, follow, validator, p2p, announce_to, bft_config } => {
            cmd_start(rpc, data_dir, key_file, follow, validator, p2p, announce_to, bft_config).await?
        }
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

/// This node's own key in `<data_dir>/node.key`, created on first start.
fn node_key(data_dir: &str) -> Result<HydraXKeypair> {
    std::fs::create_dir_all(data_dir)?;
    let path = std::path::Path::new(data_dir).join("node.key");
    let path = path.to_str().ok_or_else(|| anyhow::anyhow!("data dir path is not UTF-8"))?;
    if std::path::Path::new(path).exists() {
        info!("🔑 Loading node key from {path}");
        return load_keypair(path);
    }
    let kp = HydraXKeypair::generate();
    write_secret_file(path, &kp.to_bytes())?;
    info!("🔑 New node key saved to {path}");
    Ok(kp)
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

#[allow(clippy::too_many_arguments)]
async fn cmd_start(
    rpc_addr: String,
    data_dir: String,
    key_file: Option<String>,
    follow: Vec<String>,
    validator: Option<String>,
    p2p_addr: Option<String>,
    announce_to: Vec<String>,
    bft_config: Option<String>,
) -> Result<()> {
    let keypair = match key_file {
        Some(path) => {
            info!("🔑 Loading HYDRA-X validator key from {path}");
            load_keypair(&path)?
        }
        None => node_key(&data_dir)?,
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
    match qtrc_common::chain::known_activations(&genesis) {
        Some(a) => {
            // The live network: heights fixed in code, the same on every node.
            store.pin_activations(&a)?;
            init_state.fee_from_height = a.fee;
            init_state.sentinel_from_height = a.sentinel;
            init_state.state_root_from_height = a.state_root;
            init_state.witness_root_from_height = a.witness_root;
            info!("Known network: activation heights fixed by the chain parameters");
        }
        None => {
            init_state.fee_from_height = store.fee_from_height()?;
            init_state.sentinel_from_height = store.sentinel_from_height()?;
            init_state.state_root_from_height = store.state_root_from_height()?;
            init_state.witness_root_from_height = store.witness_root_from_height()?;
        }
    }
    // Several validators voting (BFT), on a network not fixed in code.
    let bft_peers = match &bft_config {
        Some(path) => {
            if qtrc_common::chain::known_activations(&genesis).is_some() {
                anyhow::bail!("--bft-config is for networks not fixed in code; the live network's rules come from the code");
            }
            let (from, peers) = bft::BftConfig::load(path)?;
            init_state.bft_from_height = from;
            init_state.validators = peers
                .iter()
                .map(|p| qtrc_common::state::ValidatorInfo { address: p.address.clone(), stake: 1 })
                .collect();
            info!(validators = peers.len(), bft_from_height = from, "Blocks decided by validator votes (BFT)");
            Some(peers)
        }
        None => None,
    };
    // Who signs the blocks. Without a set, the node would expect its own
    // signature on every block, which only works on the single validator.
    if bft_peers.is_some() {
        // Set above from the BFT config.
    } else if let Some(vs) = qtrc_common::chain::known_validators(&genesis) {
        init_state.validators = vs
            .into_iter()
            .map(|address| qtrc_common::state::ValidatorInfo { address, stake: 1 })
            .collect();
    } else if let Some(v) = &validator {
        let address = qtrc_crypto::Address::from_hex(v).map_err(|e| anyhow::anyhow!("--validator must be a 64-hex address: {e}"))?;
        init_state.validators = vec![qtrc_common::state::ValidatorInfo { address, stake: 1 }];
    }
    let following = !follow.is_empty();
    if following && init_state.validators.is_empty() {
        anyhow::bail!("--follow needs to know the validator: this chain has none fixed in code, pass --validator <address>");
    }
    if !following && !init_state.validators.is_empty() && !init_state.validators.iter().any(|v| v.address == keypair.address()) {
        anyhow::bail!(
            "this node's key ({}) is not a validator of this chain; start with --follow <peer> to run a follower",
            keypair.address().as_hex()
        );
    }
    info!(
        witness_root_from_height = init_state.witness_root_from_height,
        "Block headers commit to full transactions from this height"
    );
    info!(
        state_root_from_height = init_state.state_root_from_height,
        "Block headers carry the state root from this height"
    );
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
    // The BFT driver signs votes with the same key as the engine.
    let driver_key = HydraXKeypair::from_bytes(&keypair.to_bytes())?;
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

    // One of the BFT validators: the consensus thread and the p2p listener
    // that feeds it. Transactions clients send us are relayed to the others.
    let mut relay = None;
    let mut p2p_addr = p2p_addr;
    let bft_validator = bft_peers.as_ref().is_some_and(|ps| ps.iter().any(|p| p.address == engine.address));
    if let (true, Some(peers)) = (bft_validator, bft_peers.clone()) {
        let addr = p2p_addr.take().ok_or_else(|| anyhow::anyhow!("a BFT validator needs --p2p <listen address>"))?;
        let addr: std::net::SocketAddr = addr.parse().map_err(|e| anyhow::anyhow!("--p2p {addr}: {e}"))?;
        let out = bft::Outbox::new(peers.clone(), engine.address.clone())?;
        let guard_path = std::path::Path::new(&data_dir).join("bft-sign-state");
        let guard = qtrc_bft::runner::SignGuard::open(&guard_path).map_err(|e| anyhow::anyhow!("sign guard: {e}"))?;
        let (driver, inbox) = bft::Driver::new(engine.clone(), driver_key, out.clone(), guard)?;
        std::thread::spawn(move || driver.run());
        let (e, s2) = (engine.clone(), store.clone());
        tokio::spawn(async move {
            if let Err(err) = bft::serve(e, s2, inbox, peers, addr).await {
                warn!("BFT p2p listener stopped: {err:#}");
            }
        });
        relay = Some(out);
    } else {
        drop(driver_key);
    }

    let wake = p2p::Wake::new();
    if let Some(addr) = p2p_addr {
        let addr: std::net::SocketAddr = addr.parse().map_err(|e| anyhow::anyhow!("--p2p {addr}: {e}"))?;
        if !following {
            warn!("--p2p on a validator: announcements are only used by followers for now");
        }
        let (e, w) = (engine.clone(), wake.clone());
        tokio::spawn(async move {
            if let Err(err) = p2p::serve(e, w, addr).await {
                warn!("P2P listener stopped: {err:#}");
            }
        });
    }
    if !announce_to.is_empty() {
        tokio::spawn(p2p::announce_loop(engine.clone(), announce_to));
    }

    if following {
        // Follower: verify and store other nodes' blocks, produce none.
        let peers = follow
            .iter()
            .map(|u| follow::HttpPeer::new(u).map(|p| Box::new(p) as Box<dyn follow::BlockSource>))
            .collect::<Result<Vec<_>>>()?;
        info!(peers = ?follow, "Follower mode: syncing from peers, not producing blocks");
        let e = engine.clone();
        let w = wake.clone();
        std::thread::spawn(move || follow::run(e, peers, w));
    } else if !bft_validator {
        let engine_clone = engine.clone();
        tokio::spawn(async move {
            run_block_producer(engine_clone).await;
        });
    }

    // Start JSON-RPC server
    info!("JSON-RPC listening on http://{rpc_addr}");
    rpc::serve(engine, store, following, relay, rpc_addr.parse()?).await;

    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn node_key_is_created_once_and_kept() {
        let dir = std::env::temp_dir().join(format!("qtrc-node-key-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let d = dir.to_str().unwrap();
        let first = super::node_key(d).unwrap().address();
        let again = super::node_key(d).unwrap().address();
        assert_eq!(first, again, "a restart must keep the same node address");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
